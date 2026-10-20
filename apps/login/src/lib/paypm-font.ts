import localFont from "next/font/local";

export const paypmFont = localFont({
  src: [
    { path: "../assets/fonts/DMSans/DMSans-Regular.ttf", weight: "400", style: "normal" },
    { path: "../assets/fonts/DMSans/DMSans-Medium.ttf", weight: "500", style: "normal" },
    { path: "../assets/fonts/DMSans/DMSans-SemiBold.ttf", weight: "600", style: "normal" },
  ],
  display: "swap",
  fallback: ["Arial", "sans-serif"],
});
