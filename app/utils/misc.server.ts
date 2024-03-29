import { json } from "@remix-run/node"
import { nanoid } from "nanoid"

export const generateRandomToken = () => nanoid(48)

export function getDomainUrl(request: Request) {
  const host =
    request.headers.get("X-Forwarded-Host") ?? request.headers.get("host")
  if (!host) {
    throw new Error("Could not determine domain URL.")
  }
  const protocol = host.includes("localhost") ? "http" : "https"
  return `${protocol}://${host}`
}

export function badRequest<T>(data: T) {
  return json(data, { status: 400 })
}
