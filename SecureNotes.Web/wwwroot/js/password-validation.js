const MIN_LENGTH = 12;
const MIN_ENTROPY = 3.0;
const MIN_SCORE = 3;

function calculateEntropy(password) {
    if (!password) return 0;

    const frequencies = {};
    for (let char of password) {
        frequencies[char] = (frequencies[char] || 0) + 1;
    }

    let entropy = 0;
    const len = password.length;

    for (let count of Object.values(frequencies)) {
        const frequency = count / len;
        entropy -= frequency * Math.log2(frequency);
    }

    return entropy;
}

function calculateScore(password) {
    let score = 0;
    if (/[A-Z]/.test(password)) score++;  // uppercase
    if (/[a-z]/.test(password)) score++;  // lowercase
    if (/[0-9]/.test(password)) score++;  // digits
    if (/[^A-Za-z0-9]/.test(password)) score++;  // special chars
    return score;
}

function validatePassword(password) {
    if (!password) {
        return { isValid: false, message: "Password is required", entropy: 0 };
    }

    const entropy = calculateEntropy(password);
    const score = calculateScore(password);

    if (password.length < MIN_LENGTH) {
        return {
            isValid: false,
            message: `Password must be at least ${MIN_LENGTH} characters long`,
            entropy
        };
    }

    if (score < MIN_SCORE) {
        return {
            isValid: false,
            message: "Password must contain 3 of 4: uppercase, lowercase, digits, special characters",
            entropy
        };
    }

    if (entropy < MIN_ENTROPY) {
        return {
            isValid: false,
            message: `Password is too weak (entropy: ${entropy.toFixed(2)})`,
            entropy
        };
    }

    return {
        isValid: true,
        message: `Password strength: good (entropy: ${entropy.toFixed(2)})`,
        entropy
    };
}

function updatePasswordStrength(password, targetElement) {
    const result = validatePassword(password);
    targetElement.textContent = result.message;
    targetElement.style.color = result.isValid ? 'green' : 'darkred';
    return result.isValid;
}