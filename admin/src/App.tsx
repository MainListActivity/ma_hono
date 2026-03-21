import { createContext, useContext, useState } from "react";
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes
} from "react-router";
import LoginPage from "./pages/LoginPage";
import TenantsPage from "./pages/TenantsPage";
import TenantUsersPage from "./pages/TenantUsersPage";
import AuthGuard from "./components/AuthGuard";

interface AuthContextValue {
  token: string | null;
  setToken: (token: string | null) => void;
}

export const AuthContext = createContext<AuthContextValue>({
  token: null,
  setToken: () => {}
});

export const useAuth = () => useContext(AuthContext);

export default function App() {
  const [token, setTokenState] = useState<string | null>(
    () => sessionStorage.getItem("admin_session_token")
  );

  const setToken = (t: string | null) => {
    if (t === null) {
      sessionStorage.removeItem("admin_session_token");
    } else {
      sessionStorage.setItem("admin_session_token", t);
    }
    setTokenState(t);
  };

  return (
    <AuthContext.Provider value={{ token, setToken }}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route element={<AuthGuard />}>
            <Route path="/tenants" element={<TenantsPage />} />
            <Route path="/tenants/:tenantId/users" element={<TenantUsersPage />} />
          </Route>
          <Route path="*" element={<Navigate to="/tenants" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthContext.Provider>
  );
}
