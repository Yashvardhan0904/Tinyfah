/* Logo mark: a rounded tile with a "T" built purely from CSS shapes */
export function LogoMark() {
  return (
    <span
      aria-hidden="true"
      className="relative flex h-8 w-8 shrink-0 items-center justify-center rounded-[9px] bg-[#ea7336] shadow-[inset_0_1px_0_rgba(255,255,255,0.35),0_1px_2px_rgba(234,115,54,0.35)] transition-transform duration-200 group-hover:-rotate-3"
    >
      {/* T top bar */}
      <span className="absolute left-[7px] top-[8px] h-[4px] w-[18px] rounded-full bg-white" />
      {/* T stem */}
      <span className="absolute left-[14px] top-[8px] h-[16px] w-[4px] rounded-full bg-white" />
      {/* small "pixel" accent for the "tiny" idea */}
      <span className="absolute bottom-[8px] right-[7px] h-[4px] w-[4px] rounded-[1px] bg-white/70" />
    </span>
  );
}