import { Form, Link } from "@remix-run/react"
import { useEffect, useState } from "react"
import { motion } from "framer-motion"
import clsx from "clsx"
import copy from "copy-to-clipboard"
import { DocumentDuplicateIcon, CheckIcon } from "@heroicons/react/20/solid"
import { prodUrl } from "~/config"

import Card from "~/components/shared/Card"
import { subtleButtonClasses } from "~/components/shared/Buttons"
import { headlineClasses } from "~/components/shared/Headline"
import { inputClasses, labelClasses } from "~/components/Input"

interface WelcomeCardProps {
  username: string
  slug: string
  isFirstLogin: boolean
}

export default function WelcomeCard({
  username,
  isFirstLogin,
  slug,
}: WelcomeCardProps) {
  const [showFirstLogin, setShowFirstLogin] = useState(isFirstLogin)
  const [copied, setCopied] = useState(false)

  const userLink = `${prodUrl}/u/${slug}`

  useEffect(() => {
    let timeout: ReturnType<typeof setTimeout>

    if (copied) {
      timeout = setTimeout(() => {
        setCopied(false)
      }, 1000)
    }

    return () => {
      clearTimeout(timeout)
    }
  }, [copied])

  function copyUserLink() {
    copy(userLink)
    setCopied(true)
  }

  return (
    <Card>
      <h2 className={headlineClasses}>Hey {username}!</h2>
      <div className="h-4"></div>
      <FirstLoginText
        show={showFirstLogin}
        onHide={() => setShowFirstLogin(false)}
      />
      <motion.div
        className="space-y-2 overflow-hidden"
        initial={false}
        animate={{ height: showFirstLogin ? 0 : "auto" }}
        transition={{
          type: "spring",
          duration: 0.3,
          delay: 0.45,
          bounce: 0.1,
        }}
      >
        <label htmlFor="link" className={labelClasses}>
          Dein Link zum Teilen:
        </label>
        <div className="flex items-center gap-2">
          <input
            type="text"
            readOnly
            className={clsx(
              inputClasses,
              "mt-0 cursor-pointer overflow-x-scroll bg-neutral-50 text-sm sm:max-w-sm",
            )}
            value={userLink}
            onClick={() => (window.location.href = `/u/${slug}`)}
          />
          <button
            className="rounded-md border border-slate-300 bg-neutral-100 p-2 shadow-sm"
            onClick={copyUserLink}
          >
            {copied ? (
              <CheckIcon className="h-5 w-5" />
            ) : (
              <DocumentDuplicateIcon className="h-5 w-5" />
            )}
          </button>
        </div>
      </motion.div>
    </Card>
  )
}

interface FirstLoginTextProps {
  show: boolean
  onHide: () => void
}

function FirstLoginText({ show, onHide }: FirstLoginTextProps) {
  return (
    <motion.div
      className="space-y-2 overflow-hidden"
      initial={false}
      animate={{ height: show ? "auto" : 0 }}
      transition={{
        type: "spring",
        duration: 0.3,
        bounce: 0.1,
      }}
    >
      <p className="flex items-center font-semibold">
        Willkommen bei miny
        <img src="https://emojicdn.elk.sh/👋" alt="" className="ml-1 h-5 w-5" />
      </p>
      <p>
        Hier kannst du ganz einfach deine freien Termine eintragen und sie dann
        per Link verschicken. Wenn sich jemand für einen deiner Termine
        einträgt, bekommst du automatisch eine E-Mail.
      </p>
      <p>
        Tipp: In den{" "}
        <Link to="/settings" className="text-amber-800">
          Einstellungen
        </Link>{" "}
        kannst du miny auch mit deinem Kalender verbinden.
      </p>
      <p className="flex items-center">
        Viel Spaß!
        <img src="https://emojicdn.elk.sh/🎉" alt="" className="ml-1 h-5 w-5" />
      </p>
      <div className="h-2"></div>
      <Form action="." method="post" onSubmit={onHide}>
        <button
          type="submit"
          name="action"
          value="hideWelcomeText"
          className={subtleButtonClasses}
        >
          Ausblenden
        </button>
      </Form>
    </motion.div>
  )
}