export default function ErrorList({ errors }: { errors: string[] }) {
  if (errors.length === 0) return null
  return (
    <div role="alert" className="error">
      {errors.map((message) => (
        <p key={message}>{message}</p>
      ))}
    </div>
  )
}
