/*
  Warnings:

  - You are about to drop the column `userId` on the `Project` table. All the data in the column will be lost.
  - You are about to drop the `User` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "Project" DROP CONSTRAINT "Project_userId_fkey";

-- DropForeignKey
ALTER TABLE "SocialLogin" DROP CONSTRAINT "SocialLogin_userId_fkey";

-- AlterTable
ALTER TABLE "Project" DROP COLUMN "userId";

-- DropTable
DROP TABLE "User";
