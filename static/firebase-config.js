import { initializeApp } from
"https://www.gstatic.com/firebasejs/11.6.0/firebase-app.js";

import {
    initializeAuth,
    browserSessionPersistence,
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

const firebaseConfig = {
    apiKey: "AIzaSyBuSXoKTp12QO_frJykpKybe4O30fkgd7Y",
    authDomain: "forensic-lab-7e02c.firebaseapp.com",
    databaseURL: "https://forensic-lab-7e02c-default-rtdb.firebaseio.com",
    projectId: "forensic-lab-7e02c",
    storageBucket: "forensic-lab-7e02c.firebasestorage.app",
    messagingSenderId: "103054429119",
    appId: "1:103054429119:web:8f1c0e21ab8c7402cd6f0a",
    measurementId: "G-DHN3J9RVT1"
};

const app = initializeApp(firebaseConfig);

// Session inafanya kazi ndani ya tab ya browser.
const auth = initializeAuth(app, {
    persistence: browserSessionPersistence
});

const database = getDatabase(app);

export {
    app,
    auth,
    database,

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
