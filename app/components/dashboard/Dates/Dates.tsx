import type { DateWithParticipants } from "~/models/date.server"
import clsx from "clsx"
import { Link } from "@remix-run/react"
import { PlusIcon } from "@heroicons/react/20/solid"

import Card from "~/components/shared/Card"
import { subtleButtonClasses } from "~/components/shared/Buttons"
import { headlineClasses } from "~/components/shared/Headline"
import Date from "~/components/shared/Date"

interface DatesProps {
  dates: Array<DateWithParticipants>
}

export default function Dates({ dates }: DatesProps) {
  return (
    <Card>
      <div className="flex items-center justify-between">
        <h2 className={headlineClasses}>Termine</h2>
        <Link
          to="new"
          className={clsx(subtleButtonClasses, "inline-flex items-center")}
        >
          <PlusIcon className="mr-2 h-5 w-5" />
          <span>Neu</span>
        </Link>
      </div>
      <div className="h-4"></div>
      <div className="divide-y">
        {dates.map(entry => (
          <Date key={entry.id} data={entry} />
        ))}
      </div>
    </Card>
  )
}