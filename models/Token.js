const mongoose = require('mongoose');

const tokenSchema = new mongoose.Schema({
   userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
   },
   token: { type: String, required: true },
   createdAt: { type: Date, required: true, default: Date.now, expires: 3600 } // Token expires in 1 hour
});

const Token = mongoose.model('Token', tokenSchema);

module.exports = Token;
