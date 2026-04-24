const mongoose = require('mongoose');

let isConnected = false;

async function connectDB() {
  if (isConnected) return;

  const mongoUri = process.env.MONGO_URI;
  if (!mongoUri) {
    throw new Error('MONGO_URI is missing in environment');
  }

  await mongoose.connect(mongoUri, {
    autoIndex: true
  });

  isConnected = true;
  console.log('[db] MongoDB connected');
}

module.exports = {
  connectDB,
  mongoose
};
