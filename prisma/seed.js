import { PrismaClient } from '@prisma/client';
import { hashPassword } from '../src/utils/password.utils.js';

const prisma = new PrismaClient();

async function main() {
  const hashedPassword = await hashPassword('certamen123');
  
  await prisma.user.create({
    data: {
      username: 'admin',
      name: 'Gustavo Alfredo Marín Sáez',
      password: hashedPassword
    }
  });
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  }); 