
import { useState } from 'react'
import Hero from '../features/landing/Hero'
import HowItWorks from '../features/landing/HowItWorks'
import Capabilities from '../features/landing/Capabilities'
import { useScan } from '../hooks/useScan'

export default function LandingPage() {
  const [submittedUrl, setSubmittedUrl] = useState('')
  const {
    status,
    result,
    error,
    startScan,
  } = useScan()

  const handleScan = async (url) => {
    setSubmittedUrl(url)
    await startScan(url)
  }

  return (
    <>
      <Hero
        onScan={handleScan}
        submittedUrl={submittedUrl}
        status={status}
        result={result}
        error={error}
      />
      <HowItWorks />
      <Capabilities />
    </>
  )
}
