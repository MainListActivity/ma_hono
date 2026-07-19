import { useEffect } from "react";

export const PRODUCT_NAME = "MA 登录";

export function formatDocumentTitle(pageTitle?: string) {
  return pageTitle ? `${pageTitle}｜${PRODUCT_NAME}` : PRODUCT_NAME;
}

export function useDocumentTitle(pageTitle?: string) {
  useEffect(() => {
    document.title = formatDocumentTitle(pageTitle);
  }, [pageTitle]);
}
