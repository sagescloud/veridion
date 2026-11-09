import { useState } from 'react'
import Hero from '../features/landing/Hero'
import HowItWorks from '../features/landing/HowItWorks'
import Capabilities from '../features/landing/Capabilities'

export default function LandingPage() {
  const [submittedUrl, setSubmittedUrl] = useState('')

  return (
    <>
      <Hero onScan={setSubmittedUrl} submittedUrl={submittedUrl} />
      <HowItWorks />
      <Capabilities />
    </>
  )
}