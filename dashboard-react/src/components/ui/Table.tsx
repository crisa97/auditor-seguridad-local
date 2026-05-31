import { cn } from '@/utils/helpers';

interface TableProps {
  children: React.ReactNode;
  className?: string;
}

interface TableHeaderProps {
  children: React.ReactNode;
  className?: string;
}

interface TableBodyProps {
  children: React.ReactNode;
  className?: string;
}

interface TableRowProps {
  children: React.ReactNode;
  className?: string;
  onClick?: () => void;
}

interface TableCellProps {
  children: React.ReactNode;
  className?: string;
  colSpan?: number;
}

export function Table({ children, className }: TableProps) {
  return (
    <div className="table-container">
      <table className={cn('table', className)}>{children}</table>
    </div>
  );
}

export function TableHeader({ children, className }: TableHeaderProps) {
  return <thead className={cn('table-header', className)}>{children}</thead>;
}

export function TableBody({ children, className }: TableBodyProps) {
  return <tbody className={cn('table-body', className)}>{children}</tbody>;
}

export function TableRow({ children, className, onClick }: TableRowProps) {
  return (
    <tr
      className={cn('table-row', onClick && 'table-row-clickable', className)}
      onClick={onClick}
    >
      {children}
    </tr>
  );
}

export function TableCell({ children, className, colSpan }: TableCellProps) {
  return (
    <td className={cn('table-cell', className)} colSpan={colSpan}>
      {children}
    </td>
  );
}
