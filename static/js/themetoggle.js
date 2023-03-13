const btn = $("#btn-toggle");
const prefersDarkScheme = window.matchMedia("(prefers-color-scheme: dark)");

const currentTheme = localStorage.getItem("theme");
if (currentTheme == "dark") {
  btn.prop("checked", true);
  toggleTheme("dark");
} else if (currentTheme == "light") {
  btn.prop("checked", false);
  toggleTheme("light");
}

btn.change(function() {
  const theme = this.checked ? "dark" : "light";
  toggleTheme(theme);
  localStorage.setItem("theme", theme);
});

function toggleTheme(theme) {
  $("body").toggleClass("dark-theme", theme === "dark");
  $("body").toggleClass("light-theme", theme === "light");
  prefersDarkScheme.matches ? $("body").addClass("prefers-dark") : $("body").removeClass("prefers-dark");
}
