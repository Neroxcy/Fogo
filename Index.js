const axios = require('axios');

const WALLET = 'DYyirsVXXisGDF9eTzK1zoC8J6hAaGYcbTmGddohihQE'; // ← wallet kamu
const URL = 'https://faucet.fogo.io/api/faucet';

async function claim() {
  try {
    const res = await axios.post(URL, {
      address: WALLET,
      token: 'FOGO',
      amount: 1
    }, {
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0'
      }
    });
    console.log('✅ Klaim berhasil:', res.data);
  } c
