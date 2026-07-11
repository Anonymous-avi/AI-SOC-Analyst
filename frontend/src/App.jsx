import { Route, Routes } from "react-router-dom";

import AlertDetailsPage from "./pages/AlertDetailsPage";
import DashboardPage from "./pages/DashboardPage";


function App() {
  return (
    <Routes>
      <Route
        path="/"
        element={<DashboardPage />}
      />

      <Route
        path="/alerts/:alertId"
        element={<AlertDetailsPage />}
      />
    </Routes>
  );
}


export default App;