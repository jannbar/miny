import { Menu, Transition } from "@headlessui/react"
import { Fragment } from "react"
import {
  Bars3Icon,
  PlusIcon,
  ArrowRightOnRectangleIcon,
  WindowIcon,
} from "@heroicons/react/20/solid"
import { Form, Link } from "@remix-run/react"
import clsx from "clsx"
import { useOptionalUser } from "~/utils/hooks"
import { UserCircleIcon } from "@heroicons/react/24/outline"

export const itemClasses =
  "flex w-full items-center rounded-md px-2 py-2 text-sm hover:bg-slate-100"
const iconClasses = "mr-2 h-4 w-4"

export default function MenuComponent() {
  const user = useOptionalUser()

  return (
    <div className="w-56 text-right">
      <Menu as="div" className="relative inline-block text-left">
        <div>
          <Menu.Button className="inline-flex w-full items-center justify-center rounded-md bg-slate-300 px-4 py-2 text-sm font-medium hover:bg-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-slate-700 focus-visible:ring-opacity-75">
            Menü
            <Bars3Icon className="ml-2.5 -mr-1 h-4 w-4" aria-hidden="true" />
          </Menu.Button>
        </div>
        <Transition
          as={Fragment}
          enter="transition ease-out duration-100"
          enterFrom="transform opacity-0 scale-95"
          enterTo="transform opacity-100 scale-100"
          leave="transition ease-in duration-75"
          leaveFrom="transform opacity-100 scale-100"
          leaveTo="transform opacity-0 scale-95"
        >
          <Menu.Items className="absolute right-0 z-10 mt-2 w-56 origin-top-right divide-y divide-gray-100 rounded-md bg-white shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none">
            {user ? (
              <div className="flex items-center p-3 pb-2 text-sm text-slate-500">
                <UserCircleIcon className="mr-3 ml-0.5 h-4 w-4" />
                {user.name}
              </div>
            ) : null}
            {user && user.isAdmin ? (
              <div className="px-1 py-1">
                <Menu.Item>
                  {({ active }) => (
                    <Link
                      to="/admin"
                      className={clsx(itemClasses, { "bg-slate-100": active })}
                    >
                      <WindowIcon className={iconClasses} aria-hidden="true" />
                      Admin
                    </Link>
                  )}
                </Menu.Item>
              </div>
            ) : null}
            <div className="px-1 py-1 ">
              <Menu.Item>
                {({ active }) => (
                  <Link
                    to="/add"
                    className={clsx(itemClasses, { "bg-slate-100": active })}
                  >
                    <PlusIcon className={iconClasses} aria-hidden="true" />
                    Neuer Termin
                  </Link>
                )}
              </Menu.Item>
              {/* <Menu.Item>
                {({ active }) => (
                  <Link
                    to="/settings"
                    className={clsx(itemClasses, { "bg-slate-100": active })}
                  >
                    <CogIcon className={iconClasses} aria-hidden="true" />
                    Einstellungen
                  </Link>
                )}
              </Menu.Item> */}
            </div>
            <div className="px-1 py-1 ">
              <Menu.Item>
                {({ active }) => (
                  <Form action="/logout" method="post">
                    <button
                      type="submit"
                      className={clsx(itemClasses, { "bg-slate-100": active })}
                    >
                      <ArrowRightOnRectangleIcon
                        className={iconClasses}
                        aria-hidden="true"
                      />
                      Abmelden
                    </button>
                  </Form>
                )}
              </Menu.Item>
            </div>
          </Menu.Items>
        </Transition>
      </Menu>
    </div>
  )
}
