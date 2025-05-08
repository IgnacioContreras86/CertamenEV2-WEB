import { scrypt, randomBytes } from 'crypto';

export function hashPasswordWithSalt(password, salt) {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) {
        return reject(err);
      }
      resolve(`${salt}:${derivedKey.toString("hex")}`);
    });
  });
}

export function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  return hashPasswordWithSalt(password, salt);
}

export async function verifyPassword(password, hash) {
  const [salt] = hash.split(":");
  
  try {
    const hashedPassword = await hashPasswordWithSalt(password, salt);
    return hashedPassword === hash;
  } catch {
    return false;
  }
} 