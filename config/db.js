const mongoose = require('mongoose');

let connected = false;

async function connectDB() {
  if (connected) return;
  const uri = process.env.MONGO_URI;
  if (!uri) throw new Error('MONGO_URI is required');

  await mongoose.connect(uri, { autoIndex: true });
  connected = true;
  console.log('[db] MongoDB connected');
}

module.exports = { connectDB };
