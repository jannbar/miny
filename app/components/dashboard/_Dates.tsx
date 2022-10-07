import { Form, Link, useTransition } from "@remix-run/react"
import type { DateWithParticipants } from "~/models/date.server"
import {
  PlusIcon,
  PencilIcon,
  TrashIcon,
  VideoCameraIcon,
} from "@heroicons/react/20/solid"
import Card from "../shared/Card"
import { formatDate } from "~/utils"
import { headlineClasses } from "../shared/Headline"
import { subtleButtonClasses } from "../shared/Buttons"
import clsx from "clsx"

function DateSlot({ date }: { date: DateWithParticipants }) {
  const transition = useTransition()

  return (
    <div className="flex items-start justify-between gap-2 pt-4">
      <div>
        <span
          className={`relative mb-0.5 flex items-start font-medium leading-snug sm:static sm:items-center ${
            date.isAssigned ? "text-red-700" : "text-green-700"
          }`}
        >
          {date.isZoom && (
            <VideoCameraIcon className="absolute -left-5 top-[2px] mr-1 h-4 sm:static sm:left-0 sm:top-0" />
          )}
          {formatDate(date.date.toString())}, {date.startTime}
          {date.endTime && `–${date.endTime}`}
        </span>

        {date.isGroupDate && (
          <>
            <span className="block text-sm italic">
              Gruppentermin ({date.participants.length}/{date.maxParticipants})
            </span>
            {date.participants.length > 0 && (
              <ul className="mt-2 list-inside list-disc">
                {date.participants.map((participant, i) => (
                  <li key={i} className="text-sm">
                    {participant.name}
                  </li>
                ))}
              </ul>
            )}
          </>
        )}

        {!date.isGroupDate && date.isAssigned && (
          <span className="block text-sm text-slate-700">
            Mit: {date.partnerName}
          </span>
        )}

        {date.note && (
          <span
            className={`block text-sm italic ${
              date.isGroupDate && date.participants.length > 0 ? "mt-2" : "mt-1"
            }`}
          >
            Notiz: {date.note}
          </span>
        )}
      </div>
      <div>
        <div className="flex items-center space-x-2">
          <Link to={`/edit/${date.id}`}>
            <button
              className="opacity-50 transition-opacity duration-75 hover:opacity-100"
              title="Bearbeiten"
              aria-label="Termin bearbeiten"
            >
              <PencilIcon className="h-5 sm:h-4" />
            </button>
          </Link>
          <Form
            method="post"
            onSubmit={event => {
              if (
                !window.confirm("Möchtest du diesen Termin wirklich löschen?")
              ) {
                event.preventDefault()
              }
            }}
          >
            <input type="hidden" name="_method" value="delete" />
            <input type="hidden" name="id" value={date.id} />
            <button
              className="opacity-50 transition-opacity duration-75 hover:opacity-100 disabled:opacity-25"
              title="Löschen"
              aria-label="Termin löschen"
              type="submit"
              disabled={transition.state !== "idle"}
            >
              <TrashIcon className="h-5 sm:h-4" />
            </button>
          </Form>
        </div>
      </div>
    </div>
  )
}

export default function Dates({ dates }: { dates: DateWithParticipants[] }) {
  const hasDates = dates.length > 0

  return (
    <Card>
      <div className="flex items-center justify-between">
        <h2 className={headlineClasses}>Termine</h2>
        <Link
          className={clsx(
            subtleButtonClasses,
            "flex items-center gap-1 text-xs",
          )}
          to="/new"
        >
          <span>Neuer Termin</span>
          <PlusIcon className="h-3.5" />
        </Link>
      </div>
      {!hasDates && (
        <p className="mt-6 italic">
          Du hast aktuell keine Termine eingetragen.
        </p>
      )}

      {hasDates && (
        <div className="mt-3 flex flex-col space-y-4 divide-y divide-dashed">
          {dates.map(date => (
            <DateSlot date={date} key={date.id} />
          ))}
        </div>
      )}
    </Card>
  )
}