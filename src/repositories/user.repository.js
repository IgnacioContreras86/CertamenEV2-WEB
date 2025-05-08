import { PrismaClient } from '@prisma/client';
import { randomBytes } from 'crypto';
import { hashPassword, verifyPassword } from '../utils/password.utils.js';

const prisma = new PrismaClient();

export class UserRepository {
  async findByToken(token) {
    return prisma.user.findFirst({
      where: { token }
    });
  }

  async login(username, password) {
    const user = await prisma.user.findUnique({
      where: { username }
    });

    if (!user) {
      return null;
    }

    const isValid = await verifyPassword(password, user.password);
    if (!isValid) {
      return null;
    }

    const token = randomBytes(48).toString("hex");
    return prisma.user.update({
      where: { id: user.id },
      data: { token }
    });
  }

  async logout(token) {
    const user = await this.findByToken(token);
    if (!user) {
      return false;
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { token: null }
    });

    return true;
  }
} 