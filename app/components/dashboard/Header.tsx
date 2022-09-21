import { Link, Form } from "@remix-run/react"
import Backpack from "../Backpack"

export default function Header({ username }: { username: string }) {
  return (
    <div className="mb-8 flex items-center justify-between">
      <div className="flex items-center">
        <Backpack size={20} />
        <Link className="ml-2 block text-sm font-medium" to="/">
          {username}
          {username.slice(-1) === "s" ? "'" : "s"} Diensttermine
        </Link>
      </div>
      <Form action="/logout" method="post">
        <button
          type="submit"
          className="text-xs font-normal text-red-700 underline underline-offset-1 hover:text-red-600"
        >
          Abmelden
        </button>
      </Form>
    </div>
  )
}
