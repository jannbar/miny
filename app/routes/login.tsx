import type { inferSafeParseErrors } from "~/utils/validation.server"
import { useRef, useEffect } from "react"
import {
  Form,
  Link,
  useActionData,
  useTransition,
  useSearchParams,
} from "@remix-run/react"
import type { LoaderArgs, ActionArgs } from "@remix-run/node"
import { json, redirect } from "@remix-run/node"
import { z } from "zod"
import { safeRedirect } from "~/utils/auth.server"

import { createUserSession, getUserId } from "~/utils/session.server"
import { badRequest } from "~/utils/misc.server"
import { verifyLogin } from "~/models/user.server"

import Input from "~/components/shared/Input"
import Button from "~/components/shared/Buttons"
import { LoginCard, LoginWrapper } from "~/components/login"
import LoadingSpinner from "~/components/shared/LoadingSpinner"
import Toast from "~/components/shared/Toast"

export const loader = async ({ request }: LoaderArgs) => {
  const userId = await getUserId(request)
  if (userId) return redirect("/")
  return json({})
}

const validationSchema = z.object({
  email: z.string().min(1).email("Ungültige E-Mail"),
  password: z.string().min(6, "Passwort muss mind. 6 Zeichen lang sein"),
  redirectTo: z.string().default("/"),
  remember: z.enum(["on"]).optional(),
})
type LoginFields = z.infer<typeof validationSchema>
type LoginFieldErrors = inferSafeParseErrors<typeof validationSchema>

interface ActionData {
  fields: LoginFields
  errors?: LoginFieldErrors
}

export const action = async ({ request }: ActionArgs) => {
  const formData = await request.formData()
  const fields = Object.fromEntries(formData.entries()) as LoginFields
  const result = validationSchema.safeParse(fields)

  if (!result.success) {
    return badRequest<ActionData>({
      fields,
      errors: result.error.flatten(),
    })
  }

  const { email, password, remember } = result.data
  const redirectTo = safeRedirect(result.data.redirectTo)

  const user = await verifyLogin(email, password)
  if (!user) {
    return badRequest<ActionData>({
      fields: result.data,
      errors: {
        fieldErrors: {
          email: ["E-Mail oder Passwort ist falsch."],
        },
      },
    })
  }

  return createUserSession({
    request,
    userId: user.id,
    remember: remember === "on",
    redirectTo,
  })
}

export default function Login() {
  const [searchParams] = useSearchParams()
  const redirectTo = searchParams.get("redirectTo") ?? ""
  const actionData = useActionData<typeof action>()
  const transition = useTransition()

  const hasEvent = searchParams.get("event")

  const emailRef = useRef<HTMLInputElement>(null)
  const passwordRef = useRef<HTMLInputElement>(null)

  const isSubmitting =
    transition.state !== "idle" && transition.type !== "normalLoad"

  useEffect(() => {
    if (actionData?.errors?.fieldErrors.email) {
      emailRef.current?.focus()
    } else if (actionData?.errors?.fieldErrors.password) {
      passwordRef.current?.focus()
    }
  }, [actionData])

  return (
    <LoginWrapper>
      <img src="/backpack.png" className="w-10 sm:w-12" alt="" />
      <div className="h-6"></div>
      <LoginCard>
        {hasEvent === "password-resetted" ? (
          <Toast className="mb-4">
            Du kannst dich jetzt mit deinem neuen Passwort anmelden.
          </Toast>
        ) : null}
        <Form method="post">
          <fieldset disabled={isSubmitting} className="space-y-4">
            <div>
              <Input
                type="email"
                name="email"
                label="E-Mail"
                required
                autoFocus={true}
                defaultValue={actionData?.fields?.email}
                validationError={actionData?.errors?.fieldErrors.email?.join(
                  ", "
                )}
              />
            </div>

            <div>
              <Input
                type="password"
                name="password"
                label="Passwort"
                required
                minLength={6}
                defaultValue={actionData?.fields?.password}
                validationError={actionData?.errors?.fieldErrors.password?.join(
                  ", "
                )}
              />
            </div>

            <input type="hidden" name="redirectTo" value={redirectTo} />

            <div className="flex items-center">
              <input
                id="remember"
                name="remember"
                type="checkbox"
                defaultChecked
                className="h-4 w-4 rounded border-slate-300 text-slate-600 focus:ring-slate-200 focus:ring-opacity-50"
              />
              <label htmlFor="remember" className="ml-2 block text-sm">
                Angemeldet bleiben
              </label>
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <Link
                  className="block text-sm text-slate-600 underline hover:text-slate-900"
                  to="/join"
                >
                  Registrieren
                </Link>
                <Link
                  className="block text-sm text-slate-600 underline hover:text-slate-900"
                  to="/forgot-password"
                >
                  Passwort vergessen?
                </Link>
              </div>

              <Button type="submit" intent="submit" size="small" variant="icon">
                Anmelden {isSubmitting && <LoadingSpinner />}
              </Button>
            </div>
          </fieldset>
        </Form>
      </LoginCard>
      <div className="h-6"></div>
      <Link
        to="/datenschutz"
        className="text-center text-xs text-slate-600 underline"
      >
        Datenschutzerklärung
      </Link>
    </LoginWrapper>
  )
}
