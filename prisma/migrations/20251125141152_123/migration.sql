/*
  Warnings:

  - Added the required column `emailHash` to the `Certificate` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "public"."Certificate" ADD COLUMN     "emailHash" TEXT NOT NULL;
