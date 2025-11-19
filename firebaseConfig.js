// firebaseConfig.js
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyBrAN0V190iSHYEN_3P4vGIDNPElefIGyk",
  authDomain: "rfid-door-lock-8e13b.firebaseapp.com",
  projectId: "rfid-door-lock-8e13b",
  storageBucket: "rfid-door-lock-8e13b.firebasestorage.app",
  messagingSenderId: "193568206670",
  appId: "1:193568206670:web:f95083526b02bccc02f81f",
  measurementId: "G-GMFRW02DNL"
};

// Initialize Firebase (compat)
firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const db = firebase.firestore();
const functions = firebase.functions();
