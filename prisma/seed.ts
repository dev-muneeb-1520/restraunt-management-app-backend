import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  const hashedPassword = await bcrypt.hash('admin123', 10);

  await prisma.user.create({
    data: {
      email: 'admin@admin.com',
      username: 'superadmin',
      password: hashedPassword,
      role: 'ADMIN',
      profilePictureUrl: '',
    },
  });
  console.log('Admin created successfully');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
