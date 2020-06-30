const mongoose = require('mongoose');
const Schema = mongoose.Schema;

//Create Token Schema
const EmailTokenSchema = new mongoose.Schema({
  user: {
    type: Schema.Types.ObjectId,
    required: true,
    ref: 'users',
  },
  token: { type: String, required: true },
  createdAt: { type: Date, required: true, default: Date.now, expires: 43200 },
});
module.exports = EmailToken = mongoose.model('emailToken', EmailTokenSchema);
