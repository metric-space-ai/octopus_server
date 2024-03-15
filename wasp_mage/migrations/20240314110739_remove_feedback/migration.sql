/*
  Warnings:

  - You are about to drop the `Feedback` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `SocialLogin` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "Feedback" DROP CONSTRAINT "Feedback_projectId_fkey";

-- DropTable
DROP TABLE "Feedback";

-- DropTable
DROP TABLE "SocialLogin";
