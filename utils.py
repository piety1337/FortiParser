#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utility functions for FortiParser.
"""
import pandas as pd # Import pandas for easier table handling in Streamlit

def print_table(title, headers, rows):
    """Print an ASCII table given headers and rows of data."""
    cols = len(headers)
    # Handle empty rows gracefully
    if not rows:
        widths = [len(h) for h in headers]
    else:
        widths = [len(h) for h in headers]
        for r in rows:
            for i, cell in enumerate(r):
                widths[i] = max(widths[i], len(str(cell)))
                
    sep = '+' + '+'.join('-'*(w+2) for w in widths) + '+'
    print(f"\n{title}")
    print(sep)
    # header
    hrow = '|' + '|'.join(f' {headers[i].ljust(widths[i])} ' for i in range(cols)) + '|'
    print(hrow)
    print(sep)
    # rows
    for r in rows:
        row = '|' + '|'.join(f' {str(r[i]).ljust(widths[i])} ' for i in range(cols)) + '|'
        print(row)
    print(sep)

def get_table_dataframe(data: list[dict], columns: list[str], display_columns: dict = None) -> pd.DataFrame:
    """Converts a list of dictionaries (like parsed objects) into a Pandas DataFrame for Streamlit.
    
    Args:
        data: A list of dictionaries, where each dict represents a row.
        columns: A list of keys from the dictionaries to include as columns in the DataFrame.
        display_columns: An optional dictionary mapping original keys to desired display names.

    Returns:
        A Pandas DataFrame ready for display in Streamlit.
    """
    if not data:
        # Return empty DataFrame with specified columns if no data
        return pd.DataFrame(columns=display_columns.values() if display_columns else columns)
        
    df = pd.DataFrame(data)
    
    # Select and potentially rename columns
    # Make sure only existing columns are selected
    existing_columns = [col for col in columns if col in df.columns]
    df_selected = df[existing_columns]
    
    # Rename columns for display if mapping provided
    if display_columns:
        rename_map = {orig: disp for orig, disp in display_columns.items() if orig in existing_columns}
        df_selected = df_selected.rename(columns=rename_map)

    # Fill missing values with a placeholder like '-' for display
    return df_selected.fillna('-') 
