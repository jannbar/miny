import type { ActionArgs, LoaderArgs, MetaFunction } from "@remix-run/node"
import { redirect } from "@remix-run/node"
import { useState } from "react"
import { Form, Link, useActionData, useTransition } from "@remix-run/react"
import { format } from "date-fns"
import { Switch } from "@headlessui/react"
import { motion } from "framer-motion"
import { z } from "zod"

import type { inferSafeParseErrors } from "~/utils/validation.server"
import type { CreateFields } from "~/models/date.server"
import { requireUserId } from "~/utils/session.server"
import { badRequest } from "~/utils/misc.server"
import { createDates } from "~/models/date.server"

import Card from "~/components/shared/Card"
import Input from "~/components/shared/Input"
import { Calendar, dayIsSelected } from "~/components/calendar"
import { headlineClasses } from "~/components/shared/Headline"
import Button from "~/components/shared/Buttons"
import LoadingSpinner from "~/components/shared/LoadingSpinner"

const initialFormState = {
  isZoom: false,
  isFlexible: false,
  isGroup: false,
  manualPartner: false,
}

export const meta: MetaFunction = () => {
  return {
    title: "Neuer Termin",
  }
}

export async function loader({ request }: LoaderArgs) {
  await requireUserId(request)
  return null
}

export const baseDateSchema = z.object({
  days: z.string().array().min(1),
  isFlexible: z.enum(["on"]).optional(),
  start: z.string().optional(),
  end: z.string().optional(),
  flexibleStart: z.string().optional(),
  isZoom: z.enum(["on"]).optional(),
  isGroup: z.enum(["on"]).optional(),
  maxParticipants: z.string().transform(Number).optional(),
  note: z.string().optional(),
  privateNote: z.string().optional(),
})

const validationSchema = baseDateSchema
  .refine(data => (data.isFlexible !== "on" ? !!data.start : true), {
    message: "Bitte gib eine Startzeit an",
    path: ["start"],
  })
  .refine(data => (data.isFlexible === "on" ? !!data.flexibleStart : true), {
    message: "Bitte gib eine Startzeit an",
    path: ["flexibleStart"],
  })
  .refine(data => (data.isGroup === "on" ? !!data.maxParticipants : true), {
    message: "Bitte gib eine gültige Zahl an",
    path: ["maxParticipants"],
  })
type Fields = z.infer<typeof validationSchema>
type FieldErrors = inferSafeParseErrors<typeof validationSchema>

interface ActionData {
  fields: Fields
  errors?: FieldErrors
}

export async function action({ request }: ActionArgs) {
  const userId = await requireUserId(request)

  const formData = await request.formData()
  const days = formData.getAll("selectedDay")
  const { selectedDay, ...formFields } = Object.fromEntries(formData.entries())
  const fields = { ...formFields, days } as Fields
  const result = validationSchema.safeParse(fields)

  if (!result.success) {
    return badRequest<ActionData>({
      fields,
      errors: result.error.flatten(),
    })
  }

  const validData = result.data
  const data: CreateFields = {
    days: validData.days,
    isFlexible: validData.isFlexible === "on",
    start: validData.isFlexible !== "on" ? validData.start : null,
    end: validData.isFlexible !== "on" ? validData.end : null,
    flexibleStart:
      validData.isFlexible === "on" ? validData.flexibleStart : null,
    isZoom: validData.isZoom === "on",
    isGroup: validData.isGroup === "on",
    maxParticipants:
      validData.isGroup === "on" ? Number(validData.maxParticipants) : null,
    partner: null,
    note: validData.note,
    privateNote: validData.privateNote,
  }

  await createDates(data, Number(userId))

  return redirect("/")
}

export default function AddDateRoute() {
  const actionData = useActionData<ActionData>()
  const transition = useTransition()

  const [selectedDays, setSelectedDays] = useState<Date[]>([])
  const [formState, setFormState] = useState(initialFormState)

  const submitIsDisabled =
    selectedDays.length === 0 || transition.state === "submitting"

  function onSelect(day: Date) {
    if (dayIsSelected(selectedDays, day)) {
      setSelectedDays(selectedDays.filter(d => d.toString() !== day.toString()))
    } else {
      setSelectedDays([...selectedDays, day])
    }
  }

  function onReset() {
    setSelectedDays([])
  }

  return (
    <Card>
      <h1 className={headlineClasses}>Neuer Termin</h1>
      <div className="h-6"></div>
      <Calendar
        value={selectedDays}
        onSelect={onSelect}
        onReset={onReset}
        max={10}
      />
      <div className="h-8"></div>
      <Form method="post" autoComplete="off">
        {/* Map the selected days to hidden inputs */}
        {selectedDays.length > 0 &&
          selectedDays.map((day, i) => (
            <input
              key={i}
              type="hidden"
              name="selectedDay"
              value={format(day, "yyyy-MM-dd")}
            />
          ))}
        <fieldset
          className="text-sm transition-opacity disabled:opacity-60"
          disabled={transition.state === "submitting"}
        >
          <div className="space-y-6">
            {/* Flexible */}
            <Switch.Group>
              <div className="flex items-center justify-between">
                <Switch.Label>Flexible Zeit</Switch.Label>
                <Switch
                  checked={formState.isFlexible}
                  onChange={() =>
                    setFormState({
                      ...formState,
                      isFlexible: !formState.isFlexible,
                    })
                  }
                  name="isFlexible"
                  className={`${
                    formState.isFlexible ? "bg-slate-700" : "bg-slate-300"
                  } relative inline-flex h-6 w-11 items-center rounded-full`}
                >
                  <span
                    className={`${
                      formState.isFlexible ? "translate-x-6" : "translate-x-1"
                    } inline-block h-4 w-4 transform rounded-full bg-white transition`}
                  />
                </Switch>
              </div>
            </Switch.Group>
            {/* Time */}
            {formState.isFlexible ? (
              <div>
                <Input
                  name="flexibleStart"
                  label='Zeitfenster (z.B. "Vormittags")'
                  type="text"
                  required
                  defaultValue={actionData?.fields?.flexibleStart}
                  validationError={actionData?.errors?.fieldErrors.flexibleStart?.join(
                    ", "
                  )}
                />
              </div>
            ) : (
              <div className="flex items-center justify-between gap-6">
                <div className="flex-1">
                  <Input
                    name="start"
                    label="Von"
                    type="time"
                    required
                    defaultValue={actionData?.fields.start}
                    validationError={actionData?.errors?.fieldErrors.start?.join(
                      ", "
                    )}
                  />
                </div>
                <div className="flex-1">
                  <Input
                    name="end"
                    label="Bis"
                    type="time"
                    defaultValue={actionData?.fields.end}
                    validationError={actionData?.errors?.fieldErrors.end?.join(
                      ", "
                    )}
                  />
                </div>
              </div>
            )}
            {/* Zoom */}
            <Switch.Group>
              <div className="flex items-center justify-between">
                <Switch.Label>Zoom Termin</Switch.Label>
                <Switch
                  checked={formState.isZoom}
                  onChange={() =>
                    setFormState({ ...formState, isZoom: !formState.isZoom })
                  }
                  name="isZoom"
                  className={`${
                    formState.isZoom ? "bg-slate-700" : "bg-slate-300"
                  } relative inline-flex h-6 w-11 items-center rounded-full`}
                >
                  <span
                    className={`${
                      formState.isZoom ? "translate-x-6" : "translate-x-1"
                    } inline-block h-4 w-4 transform rounded-full bg-white transition`}
                  />
                </Switch>
              </div>
            </Switch.Group>
          </div>
          {/* Group */}
          <div className="h-6"></div>
          <Switch.Group>
            <div className="flex items-center justify-between">
              <Switch.Label>Gruppentermin</Switch.Label>
              <Switch
                checked={formState.isGroup}
                onChange={() =>
                  setFormState({ ...formState, isGroup: !formState.isGroup })
                }
                disabled={formState.manualPartner}
                name="isGroup"
                className={`${
                  formState.isGroup ? "bg-slate-700" : "bg-slate-300"
                } relative inline-flex h-6 w-11 items-center rounded-full disabled:opacity-60`}
              >
                <span
                  className={`${
                    formState.isGroup ? "translate-x-6" : "translate-x-1"
                  } inline-block h-4 w-4 transform rounded-full bg-white transition`}
                />
              </Switch>
            </div>
          </Switch.Group>
          <motion.div
            initial={false}
            animate={{ height: formState.isGroup ? "auto" : 0 }}
            className="relative overflow-hidden"
            transition={{
              type: "spring",
              duration: 0.3,
              bounce: 0.1,
            }}
          >
            <div className="h-6"></div>
            <Input
              label="Maximale Teilnehmer"
              name="maxParticipants"
              type="number"
              max="50"
              min="1"
              maxLength={2}
              pattern="[0-9]"
              required={formState.isGroup}
              defaultValue={actionData?.fields.maxParticipants}
              validationError={actionData?.errors?.fieldErrors.maxParticipants?.join(
                ", "
              )}
            />
          </motion.div>
          {/* Note */}
          <div className="h-6"></div>
          <Input
            label="Notiz"
            name="note"
            type="text"
            defaultValue={actionData?.fields.note}
            validationError={actionData?.errors?.fieldErrors.note?.join(", ")}
          />
          {/* Private Note */}
          <div className="h-6"></div>
          <Input
            label="Private Notiz (nur für dich sichtbar)"
            name="privateNote"
            type="text"
            defaultValue={actionData?.fields.privateNote}
            validationError={actionData?.errors?.fieldErrors.privateNote?.join(
              ", "
            )}
          />
          {/* Submit */}
          <div className="h-10"></div>
          <div className="flex items-center justify-between">
            <Link to="/" className="text-xs underline underline-offset-1">
              Zurück
            </Link>
            <Button
              type="submit"
              disabled={submitIsDisabled}
              intent="submit"
              variant="icon"
              size="small"
            >
              Speichern
              {transition.state === "submitting" && <LoadingSpinner />}
            </Button>
          </div>
        </fieldset>
      </Form>
    </Card>
  )
}
