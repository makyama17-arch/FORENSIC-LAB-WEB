// ============================================
// FORENSIC LAB
// FIREBASE CONFIGURATION
// ============================================

import { initializeApp } from
"https://www.gstatic.com/firebasejs/11.6.0/firebase-app.js";

import {
    getAuth,
    createUserWithEmailAndPassword,
    signInWithEmailAndPassword,
    signOut,
    onAuthStateChanged,
    updateProfile,
    sendPasswordResetEmail,
    sendEmailVerification
} from
"https://www.gstatic.com/firebasejs/11.6.0/firebase-auth.js";

import {
    getDatabase,
    ref,
    set,
    get,
    update,
    push,
    remove,
    onValue,
    serverTimestamp
} from
"https://www.gstatic.com/firebasejs/11.6.0/firebase-database.js";


// ============================================
// FIREBASE PROJECT CONFIGURATION
// ============================================

const firebaseConfig = {

    apiKey: "AIzaSyBuSXoKTp12QO_frJykpKybe4O30fkgd7Y",

    authDomain:
        "forensic-lab-7e02c.firebaseapp.com",

    databaseURL:
        "https://forensic-lab-7e02c-default-rtdb.firebaseio.com",

    projectId:
        "forensic-lab-7e02c",

    storageBucket:
        "forensic-lab-7e02c.firebasestorage.app",

    messagingSenderId:
        "103054429119",

    appId:
        "1:103054429119:web:8f1c0e21ab8c7402cd6f0a",

    measurementId:
        "G-DHN3J9RVT1"

};


// ============================================
// INITIALIZE FIREBASE APP
// ============================================

const app = initializeApp(firebaseConfig);


// ============================================
// FIREBASE AUTHENTICATION
// ============================================

const auth = getAuth(app);


// ============================================
// FIREBASE REALTIME DATABASE
// ============================================

const database = getDatabase(app);


// ============================================
// EXPORT FIREBASE SERVICES
// ============================================

export {

    app,

    auth,

    database,

    getAuth,

    getDatabase,

    createUserWithEmailAndPassword,

    signInWithEmailAndPassword,

    signOut,

    onAuthStateChanged,

    updateProfile,

    sendPasswordResetEmail,

    sendEmailVerification,

    ref,

    set,

    get,

    update,

    push,

    remove,

    onValue,

    serverTimestamp

};
