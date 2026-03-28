import express from 'express';
import fetch from 'node-fetch';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import crypto from 'crypto';
import 'dotenv/config';

const app = express();
const PORT = process.env.PORT || 3000;
const SHOP = process.env.SHOPIFY_SHOP_DOMAIN;
const TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;

// CORS — only needed for direct (non-proxy) calls
app.use(cors({
  origin: ['https://wkeey.com', 'https://wkeey.myshopify.com'],
  methods: ['GET'],
}));

// Rate limiting
app.use(rateLimit({ windowMs: 60_000, max: 30 }));
app.use(express.json());

// Shopify App Proxy HMAC verification
function verifyShopifyProxy(req, res, next) {
  const { signature, ...params } = req.query;
  if (!signature) return res.status(401).json({ error: 'Missing signature' });
  const message = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
  const digest = crypto.createHmac('sha256', process.env.SHOPIFY_API_SECRET).update(message).digest('hex');
  if (digest !== signature) return res.status(401).json({ error: 'Invalid signature' });
  next();
}

// Orders route — protected by proxy signature
app.get('/orders/recent', verifyShopifyProxy, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 5, 50);
  try {
    const response = await fetch(
      `https://${SHOP}/admin/api/2025-01/orders.json?limit=${limit}&status=any&fields=id,name,customer,fulfillment_status`,
      { headers: { 'X-Shopify-Access-Token': TOKEN } }
    );
    if (!response.ok) throw new Error(`Shopify: ${response.status}`);
    const { orders } = await response.json();
    res.json({
      success: true,
      orders: orders.map(o => ({
        orderId: o.name,
        customerName: o.customer ? `${o.customer.first_name} ${o.customer.last_name}`.trim() : 'Guest',
        fulfillmentStatus: o.fulfillment_status ?? 'unfulfilled',
      })),
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/health', (_, res) => res.json({ status: 'ok' }));
app.listen(PORT, () => console.log(`Running on :${PORT}`));
