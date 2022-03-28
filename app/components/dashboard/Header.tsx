import { Link, Form } from 'remix'

export default function Header({ username }: { username: string }) {
  return (
    <div className="mb-8 flex items-center justify-between">
      <div className="flex items-center">
        <div className="block rounded-lg bg-red-400 bg-opacity-20 p-2">
          <img
            src="https://emojicdn.elk.sh/🎒"
            className="h-5"
            height={20}
            width={20}
          />
        </div>
        <Link className="ml-2 block text-sm font-medium" to="/">
          {username}
          {username.slice(-1) === 's' ? "'" : 's'} Diensttermine
        </Link>
      </div>
      <Form action="/logout" method="post">
        <button
          type="submit"
          className="text-xs text-red-700 underline underline-offset-1 hover:text-red-600"
        >
          Abmelden
        </button>
      </Form>
    </div>
  )
}
