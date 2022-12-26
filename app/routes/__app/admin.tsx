import type { DataFunctionArgs, MetaFunction } from "@remix-run/node"
import { json } from "@remix-run/node"
import { redirect } from "@remix-run/node"
import { useLoaderData } from "@remix-run/react"
import React from "react"

import { requireAdmin } from "~/utils/session.server"
import { prisma } from "~/utils/db.server"

import Card from "~/components/shared/Card"
import Stat from "~/components/admin/Stat"
import UserTable from "~/components/admin/UserTable"
import Button from "~/components/shared/Buttons"

const USERS_PER_PAGE = 50

function getUsers(page: number, orderBy: string, sort: string) {
  return prisma.user.findMany({
    select: {
      id: true,
      name: true,
      email: true,
      createdAt: true,
      loginCount: true,
    },
    skip: page > 1 ? (page - 1) * USERS_PER_PAGE : 0,
    take: USERS_PER_PAGE,
    orderBy: {
      [orderBy]: sort,
    },
  })
}

export type Users = Awaited<ReturnType<typeof getUsers>>

interface LoaderData {
  totalUsers: number
  totalAppointments: number
  totalLogins: string
  users: Users
  page: number
  totalPages: number
}

export async function loader({ request }: DataFunctionArgs) {
  await requireAdmin(request)

  // Get search params
  const searchParams = new URL(request.url).searchParams
  let page = searchParams.get("page") ?? 1
  if (typeof page === "string") {
    page = Number(page)
  }
  const orderBy = searchParams.get("orderBy") ?? "id"
  const sort = searchParams.get("sort") ?? "asc"
  if (page < 1 || isNaN(page)) throw redirect("?page=1")

  const totalUsers = await prisma.user.count()
  const totalAppointments = await prisma.appointment.count()

  const logins = await prisma.user.aggregate({
    _sum: {
      loginCount: true,
    },
  })
  const totalLogins = new Intl.NumberFormat("de-DE").format(
    Number(logins._sum.loginCount)
  )

  const totalPages = Math.ceil(totalUsers / USERS_PER_PAGE)

  const users = await getUsers(page, orderBy, sort)

  return json<LoaderData>({
    totalUsers,
    totalAppointments,
    totalLogins,
    users,
    page,
    totalPages,
  })
}

export const meta: MetaFunction = () => {
  return {
    title: "Admin",
  }
}

function Label({ children }: React.PropsWithChildren) {
  return (
    <>
      <h2 className="text-sm font-semibold uppercase tracking-wider text-sky-700">
        {children}
      </h2>
      <div className="h-3 sm:h-4"></div>
    </>
  )
}

export default function AdminDashboard() {
  // Hacky, but it works
  const data = useLoaderData() as unknown as LoaderData

  return (
    <div className="space-y-6 font-mono">
      <Card>
        <div>
          <h1 className="text-lg font-bold text-sky-800">Admin Dashboard</h1>
          <div className="h-6"></div>
          <Label>Statistik</Label>
          <div className="grid grid-cols-3 gap-4">
            <Stat value={data.totalUsers} label="Benutzer" />
            <Stat value={data.totalAppointments} label="Termine" />
            <Stat value={data.totalLogins} label="Logins" />
          </div>
        </div>
      </Card>
      <Card className="overflow-scroll">
        <Label>Benutzer</Label>
        <UserTable
          users={data.users}
          activePage={data.page}
          pages={data.totalPages}
        />
      </Card>
      <Card>
        <Label>Scripts</Label>
        <Button
          intent="submit"
          onClick={() => alert("Funktioniert noch nicht")}
        >
          DB aufräumen
        </Button>
      </Card>
    </div>
  )
}
