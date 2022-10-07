import type { ActionArgs, LoaderArgs } from "@remix-run/node"
import { typedjson, useTypedLoaderData } from "remix-typedjson"

import { requireUser } from "~/session.server"
import { increaseLoginCount } from "~/models/user.server"

import WelcomeCard from "~/components/dashboard/WelcomeCard"
import Dates from "~/components/dashboard/Dates"
import { getDatesByUserId } from "~/models/date.server"

export async function loader({ request }: LoaderArgs) {
  const user = await requireUser(request)
  const isFirstLogin = user.loginCount === 0

  const dates = await getDatesByUserId(user.id)

  return typedjson({
    username: user.name,
    isFirstLogin,
    slug: user.slug,
    dates,
  })
}

export async function action({ request }: ActionArgs) {
  const user = await requireUser(request)
  const formData = await request.formData()
  const action = formData.get("action")

  switch (action) {
    case "hideWelcomeText":
      await increaseLoginCount(user)
      break
  }

  return new Response(`Unsupported intent: ${action}`, { status: 400 })
}

export default function IndexRoute() {
  const { username, isFirstLogin, slug, dates } =
    useTypedLoaderData<typeof loader>()

  return (
    <div className="space-y-6">
      <WelcomeCard
        username={username}
        isFirstLogin={isFirstLogin}
        slug={slug as string}
      />
      <Dates dates={dates} />
    </div>
  )
}