import type { User } from "@prisma/client"
import bcrypt from "bcryptjs"
import { nanoid } from "nanoid"

import { prisma } from "~/utils/db.server"

export type { User } from "@prisma/client"

async function slugify(username: string) {
  let preferredSlug = username.trim().replace(" ", "-").toLowerCase()

  const slugAlreadyExists = await getUserBySlug(preferredSlug)

  if (slugAlreadyExists) {
    const random = nanoid(10)
    return `${preferredSlug}-${random}`
  }

  return preferredSlug
}

export async function getUserById(id: User["id"]) {
  return prisma.user.findUnique({ where: { id } })
}

export async function getUserByEmail(email: User["email"]) {
  return prisma.user.findUnique({ where: { email } })
}

export async function getUserBySlug(slug: string) {
  return prisma.user.findFirst({ where: { slug } })
}

export async function createUser(
  email: User["email"],
  password: User["password"],
  name: User["name"]
) {
  const hashedPassword = await bcrypt.hash(password, 10)
  const slug = await slugify(name)

  return prisma.user.create({
    data: {
      name: name.trim(),
      email,
      password: hashedPassword,
      slug,
    },
  })
}

export async function verifyLogin(
  email: User["email"],
  password: User["password"]
) {
  const user = await getUserByEmail(email)
  if (!user || !user.password) {
    return null
  }

  const isValid = await bcrypt.compare(password, user.password)
  if (!isValid) {
    return null
  }

  await increaseLoginCount(user.id)

  const { password: _password, ...userWithoutPassword } = user

  return userWithoutPassword
}

export async function increaseLoginCount(userId: User["id"]) {
  return prisma.user.update({
    where: {
      id: userId,
    },
    data: {
      loginCount: {
        increment: 1,
      },
    },
  })
}

export async function resetUserPassword({
  userId,
  password,
}: {
  userId: User["id"]
  password: User["password"]
}) {
  const hashedPassword = await bcrypt.hash(password, 10)

  // Delete any existing reset tokens for the user
  await prisma.passwordResetToken.deleteMany({
    where: {
      userId,
    },
  })

  // Update the password
  return prisma.user.update({
    where: {
      id: userId,
    },
    data: {
      password: hashedPassword,
    },
  })
}

export async function deleteUser(userId: User["id"]) {
  return prisma.user.delete({
    where: {
      id: userId,
    },
  })
}

export async function triggerPrivate(userId: User["id"]) {
  const user = await getUserById(userId)

  if (!user || !user.isAdmin) {
    throw new Error("invalid user")
  }

  return prisma.user.update({
    where: {
      id: user.id,
    },
    data: {
      isPrivate: !user.isPrivate,
    },
  })
}
