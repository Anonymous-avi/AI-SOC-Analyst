import { Search } from "lucide-react";

function SearchBar({ searchTerm, setSearchTerm }) {
  return (
    <div className="search-wrap">
      <Search className="search-icon" size={18} />

      <input
        type="text"
        placeholder="Search alerts, IPs, attack types, or alert IDs"
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
        className="search-field"
      />
    </div>
  );
}

export default SearchBar;