const fs = require('fs');

// Function to generate a random string of letters
function generateRandomLetters(length) {
    const chars = 'abcdefghijklmnopqrstuvwxyz';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// Function to generate a random string of numbers
function generateRandomNumbers(length) {
    const chars = '0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// Generate a random BUID
(async () => {
    const letters = generateRandomLetters(3); // Generate 3 random letters
    const numbers = generateRandomNumbers(3); // Generate 3 random numbers
    const BUID = letters + numbers; // Combine the letters and numbers
    // Display the generated BUID
    console.log("###############################################");
    console.log("Generated BUID to use on Contract:", BUID);
    console.log("###############################################");

    console.log("###############################################");
    console.log("File writed on migrations/generateBUID.txt");
    console.log("###############################################");
    fs.writeFileSync('./migrations/generatedBUID.txt',`Generated BussinessId to use on deploy migration: ${BUID}`);
})();
