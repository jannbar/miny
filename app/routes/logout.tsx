import type { ActionArgs } from "@remix-run/node"
import { redirect } from "@remix-run/node"

import { logout } from "~/utils/session.server"
import { safeRedirect } from "~/utils/auth.server"

export async function action({ request }: ActionArgs) {
  const formData = await request.formData()
  return logout(request, safeRedirect(formData.get("redirectTo")))
}

export async function loader() {
  return redirect("/")
}
