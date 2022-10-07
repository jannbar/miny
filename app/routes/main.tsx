import { type LoaderArgs, type ActionArgs } from "@remix-run/node"
import type { TypedMetaFunction } from "remix-typedjson"
import { Link } from "@remix-run/react"
import { typedjson, useTypedLoaderData } from "remix-typedjson"
import { requireUser } from "~/session.server"
import { deleteDate, getDatesByUserId } from "~/models/date.server"
import { badRequest } from "~/utils"

import Container from "~/components/Container"
import Header from "~/components/dashboard/Header"
import Welcome from "~/components/dashboard/Welcome"
import Dates from "~/components/dashboard/Dates"

export const loader = async ({ request }: LoaderArgs) => {
  const user = await requireUser(request)
  const dates = await getDatesByUserId(user.id)

  return typedjson({ user, dates })
}

export const action = async ({ request }: ActionArgs) => {
  const formData = await request.formData()
  const method = formData.get("_method")
  const dateId = formData.get("id")

  if (
    typeof method !== "string" ||
    typeof dateId !== "string" ||
    method !== "delete"
  ) {
    throw badRequest({ formError: "Ungültige Anfrage" })
  }

  await deleteDate(Number(dateId))
  return null
}

export const meta: TypedMetaFunction<typeof loader> = ({ data }) => {
  return {
    title: `${data.user.name}${
      data.user.name.slice(-1) === "s" ? "'" : "s"
    } Diensttermine`,
  }
}

export default function Dashboard() {
  const { user, dates } = useTypedLoaderData<typeof loader>()

  return (
    <div className="py-10">
      <Container>
        <Header username={user.name} />
        <div className="h-6"></div>
        <Welcome user={user} />
        <div className="h-6"></div>
        <Dates dates={dates} />
        <div className="mt-4 text-center text-xs text-slate-500">
          <span className="block">
            v1.0 &middot; Danke für die Idee, Linda!
          </span>
          <a
            href="https://github.com/wh1zk1d/miny/blob/main/CHANGELOG.md"
            target="_blank"
            rel="noreferrer"
            title="Changelog"
            className="underline underline-offset-1"
          >
            Changelog
          </a>{" "}
          &middot;{" "}
          <Link to="/datenschutz" className="underline underline-offset-1">
            Datenschutzerklärung
          </Link>
        </div>
      </Container>
    </div>
  )
}