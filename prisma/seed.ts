// import { PrismaClient } from '@prisma/client';
// import * as bcrypt from 'bcrypt';

// const prisma = new PrismaClient();

// async function main() {
//   const hashedPassword = await bcrypt.hash('admin123', 10);

//   await prisma.user.create({
//     data: {
//       email: 'admin@admin.com',
//       username: 'superadmin',
//       password: hashedPassword,
//       role: 'ADMIN',
//       profilePicture: "",
//     },
//   });
//   console.log('Admin created successfully');
// }

// main()
//   .catch((e) => {
//     console.error(e);
//     process.exit(1);
//   })
//   .finally(async () => {
//     await prisma.$disconnect();
//   });

// async function main() {
//   const usersData = [
//     // STAFF
//     ...Array.from({ length: 5 }, (_, i) => ({
//       username: `staff${i + 1}`,
//       email: `staff${i + 1}@example.com`,
//       password: 'password123',
//       role: 'STAFF',
//     })),
//     // MANAGER
//     ...Array.from({ length: 3 }, (_, i) => ({
//       username: `manager${i + 1}`,
//       email: `manager${i + 1}@example.com`,
//       password: 'password123',
//       role: 'MANAGER',
//     })),
//     // CHEF
//     ...Array.from({ length: 3 }, (_, i) => ({
//       username: `chef${i + 1}`,
//       email: `chef${i + 1}@example.com`,
//       password: 'password123',
//       role: 'CHEF',
//     })),
//   ];

//   for (const user of usersData) {
//     const hashedPassword = await bcrypt.hash(user.password, 10);
//     await prisma.user.create({
//       data: {
//         username: user.username,
//         email: user.email,
//         password: hashedPassword,
//         role: user.role as any,
//         profilePictureUrl: '',
//         refreshToken: '',
//       },
//     });
//   }

//   console.log('✅ Users seeded successfully!');
// }

// main()
//   .catch((e) => {
//     console.error(e);
//     process.exit(1);
//   })
//   .finally(async () => {
//     await prisma.$disconnect();
//   });
