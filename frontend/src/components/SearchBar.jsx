function SearchBar({ value, onChange }) {
  return (
    <div className="mb-6">
      <input
        type="text"
        placeholder="Search by Alert ID, IP or Attack Type..."
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-xl border border-slate-700 bg-slate-900 px-5 py-3 text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
      />
    </div>
  );
}

export default SearchBar;