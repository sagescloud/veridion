import { useCallback, useSyncExternalStore } from 'react'

const STORAGE_KEY = 'veridion-theme'
const listeners = new Set()

// The initial value is set by the inline script in index.html before React loads.
const read = () => (document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light')

const subscribe = (callback) => {
  listeners.add(callback)
  return () => listeners.delete(callback)
}

export function useTheme() {
  const theme = useSyncExternalStore(subscribe, read, () => 'light')

  const setTheme = useCallback((next) => {
    document.documentElement.dataset.theme = next
    try {
      localStorage.setItem(STORAGE_KEY, next)
    } catch {
      /* storage unavailable: the choice just won't persist */
    }
    listeners.forEach((listener) => listener())
  }, [])

  const toggleTheme = useCallback(() => {
    setTheme(read() === 'dark' ? 'light' : 'dark')
  }, [setTheme])

  return { theme, setTheme, toggleTheme }
}
