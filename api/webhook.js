import crypto from 'crypto';

function verifySignature(payload, signature, secret) {
  if (!secret) return true;
  const computed = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(signature));
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const rawBody = JSON.stringify(req.body);
    const signature = req.headers['x-signature'];
    const secret = process.env.LEMONSQUEEZY_WEBHOOK_SECRET;

    if (secret && signature && !verifySignature(rawBody, signature, secret)) {
      return res.status(401).json({ error: 'Invalid signature' });
    }

    const eventName = req.body?.meta?.event_name;
    console.log(`[WEBHOOK] Event: ${eventName}`);
    return res.status(200).json({ message: `Event ${eventName} received` });
  } catch (error) {
    console.error('[ERROR] Webhook:', error);
    return res.status(200).json({ message: 'Processed with errors' });
  }
};
