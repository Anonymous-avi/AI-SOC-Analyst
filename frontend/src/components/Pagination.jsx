function Pagination({
  currentPage,
  totalPages,
  setCurrentPage,
}) {
  return (
    <div className="mt-6 flex items-center justify-center gap-4">
      <button
        onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
        disabled={currentPage === 1}
        className="rounded-lg border border-slate-700 px-4 py-2 text-white disabled:opacity-40"
      >
        Previous
      </button>

      <span className="text-slate-300">
        Page {currentPage} of {totalPages}
      </span>

      <button
        onClick={() =>
          setCurrentPage((p) =>
            Math.min(totalPages, p + 1)
          )
        }
        disabled={currentPage === totalPages}
        className="rounded-lg border border-slate-700 px-4 py-2 text-white disabled:opacity-40"
      >
        Next
      </button>
    </div>
  );
}

export default Pagination;