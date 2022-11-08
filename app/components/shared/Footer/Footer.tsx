import { Link } from "@remix-run/react"
import { version } from "~/config"

export default function Footer() {
  return (
    <footer className="text-center text-xs text-slate-500">
      <span>v{version}</span> &middot;{" "}
      <a
        href="https://minyapp.notion.site/Changelog-a1bee6e67715408a8db774bfa4ef1293"
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
    </footer>
  )
}
