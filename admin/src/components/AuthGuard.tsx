import { Navigate, Outlet } from "react-router";
import { useAuth } from "../App";
import { LOGIN_ROUTE } from "../routes";
import Layout from "./Layout";

export default function AuthGuard() {
  const { token } = useAuth();
  if (!token) return <Navigate to={LOGIN_ROUTE} replace />;
  return <Layout><Outlet /></Layout>;
}
