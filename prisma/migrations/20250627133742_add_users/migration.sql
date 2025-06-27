/*
  Warnings:

  - Changed the type of `role` on the `User` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.

*/
-- CreateEnum
CREATE TYPE "Role" AS ENUM ('ADMIN', 'MANAGER', 'STAFF');

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "refreshToken" TEXT,
DROP COLUMN "role",
ADD COLUMN     "role" "Role" NOT NULL;
